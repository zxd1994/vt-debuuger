
// HyperDbgToolDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "HyperDbgTool.h"
#include "HyperDbgToolDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CHyperDbgToolDlg 对话框



CHyperDbgToolDlg::CHyperDbgToolDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_HYPERDBGTOOL_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CHyperDbgToolDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CHyperDbgToolDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_START, &CHyperDbgToolDlg::OnBnClickedButtonStart)
	ON_BN_CLICKED(IDC_BUTTON_STOP, &CHyperDbgToolDlg::OnBnClickedButtonStop)
END_MESSAGE_MAP()


// CHyperDbgToolDlg 消息处理程序

BOOL CHyperDbgToolDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	
	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}
	
	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CHyperDbgToolDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CHyperDbgToolDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CHyperDbgToolDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

#include "Function.h"
#include "loadDriver.h"
#include "CLoadDriver.h"
#define DriverName0 L"HyperVisor.sys"
#define DriverName L"HyperDbg.sys"
CLoadDriver Driver;
#define CTL_LOAD_DRIVER        0x800
#define CTL_UNLOAD_DRIVER      0x801

#include "downloadSymbolsTest.h"

void CHyperDbgToolDlg::OnBnClickedButtonStart()
{
	// TODO: 在此添加控件通知处理程序代码

	extern SYMBOLS_DATA SymbolsData;
	PVOID InBufer;
	ULONG Insize;
	PVOID OutBufer;
	ULONG Outsize;
	ULONG Retsize;
	InBufer = 0;

	OutBufer = 0;
	Outsize = 0;

	WCHAR DriverPatch[MAX_PATH];
	if (!GetCurrentDirectory(MAX_PATH, DriverPatch))
	{
		MessageBoxA(NULL, "GetCurrentDirectory failed", "error", MB_ICONERROR);
		return;
	}
	wcscat_s(DriverPatch, L"\\");
	wcscat_s(DriverPatch, DriverName0);
	installDriver(L"HyperVisor",L"HyperVisor", DriverPatch);
	startDriver(L"HyperVisor");

	char str[260] = "SRV*D:\\vt\\HyperHide-master\\x64\\Release\\Symbols*http://msdl.microsoft.com/download/symbols";

	if (Driver.Load(DriverName))
	{
		if (LoadSymbols(str))
		{
			InBufer = &SymbolsData;
			Insize = sizeof(SYMBOLS_DATA);
			if (!Driver.DeviceControl(CTL_CODE(FILE_DEVICE_UNKNOWN, CTL_LOAD_DRIVER, METHOD_BUFFERED, FILE_ANY_ACCESS), InBufer, Insize, OutBufer, Outsize, &Retsize))
			{
				char chmsg[260];
				sprintf_s(chmsg, "DeviceControl CTL_LOAD_DRIVER failed:%d", GetLastError());
				MessageBoxA(NULL,chmsg, "error", MB_ICONERROR);
			}		
		}
		else
		{
			MessageBoxA(NULL, "LoadSymbols error", "error", MB_ICONERROR);
		}
	}
	else
	{
		MessageBoxA(NULL, "Load driver failed", "error", MB_ICONERROR);
	}
}


void CHyperDbgToolDlg::OnBnClickedButtonStop()
{
	// TODO: 在此添加控件通知处理程序代码
	PVOID InBufer;
	ULONG Insize;
	PVOID OutBufer;
	ULONG Outsize;
	ULONG Retsize;
	InBufer = 0;
	Insize = 0;
	OutBufer = 0;
	Outsize = 0;
	if (Driver.DeviceControl(CTL_CODE(FILE_DEVICE_UNKNOWN, CTL_UNLOAD_DRIVER, METHOD_BUFFERED, FILE_ANY_ACCESS), InBufer, Insize, OutBufer, Outsize, &Retsize))
	{
		Driver.UnLoad(DriverName);
		//Sleep(5000);
		//stopDriver(L"HyperVisor");
	}
}
