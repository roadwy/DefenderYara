
rule Trojan_BAT_BMassKeyLogger_MTB{
	meta:
		description = "Trojan:BAT/BMassKeyLogger!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 35 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 74 70 45 6e 61 62 6c 65 } //01 00  FtpEnable
		$a_01_1 = {46 74 70 48 6f 73 74 } //01 00  FtpHost
		$a_01_2 = {46 74 70 55 73 65 72 } //01 00  FtpUser
		$a_01_3 = {46 74 70 50 61 73 73 } //01 00  FtpPass
		$a_01_4 = {46 74 70 50 6f 72 74 } //01 00  FtpPort
		$a_01_5 = {45 6d 61 69 6c 45 6e 61 62 6c 65 } //01 00  EmailEnable
		$a_01_6 = {45 6d 61 69 6c 41 64 64 72 65 73 73 } //01 00  EmailAddress
		$a_01_7 = {45 6d 61 69 6c 53 65 6e 64 54 6f } //01 00  EmailSendTo
		$a_01_8 = {45 6d 61 69 6c 50 61 73 73 } //01 00  EmailPass
		$a_01_9 = {45 6d 61 69 6c 50 6f 72 74 } //01 00  EmailPort
		$a_01_10 = {45 6d 61 69 6c 53 73 6c } //01 00  EmailSsl
		$a_01_11 = {45 6d 61 69 6c 43 6c 69 65 6e 74 } //01 00  EmailClient
		$a_01_12 = {50 61 6e 65 6c 45 6e 61 62 6c 65 } //01 00  PanelEnable
		$a_01_13 = {50 61 6e 65 6c 48 6f 73 74 } //01 00  PanelHost
		$a_01_14 = {45 78 69 74 41 66 74 65 72 44 65 6c 69 76 65 72 79 } //01 00  ExitAfterDelivery
		$a_01_15 = {53 65 6c 66 44 65 73 74 72 75 63 74 } //01 00  SelfDestruct
		$a_01_16 = {45 6e 61 62 6c 65 4d 75 74 65 78 } //01 00  EnableMutex
		$a_01_17 = {45 6e 61 62 6c 65 41 6e 74 69 53 61 6e 64 62 6f 78 69 65 } //01 00  EnableAntiSandboxie
		$a_01_18 = {45 6e 61 62 6c 65 41 6e 74 69 56 4d 77 61 72 65 } //01 00  EnableAntiVMware
		$a_01_19 = {45 6e 61 62 6c 65 41 6e 74 69 44 65 62 75 67 67 65 72 } //01 00  EnableAntiDebugger
		$a_01_20 = {45 6e 61 62 6c 65 57 44 45 78 63 6c 75 73 69 6f 6e } //01 00  EnableWDExclusion
		$a_01_21 = {45 6e 61 62 6c 65 53 65 61 72 63 68 41 6e 64 55 70 6c 6f 61 64 } //01 00  EnableSearchAndUpload
		$a_01_22 = {45 6e 61 62 6c 65 53 70 72 65 61 64 55 73 62 } //01 00  EnableSpreadUsb
		$a_01_23 = {45 6e 61 62 6c 65 4b 65 79 6c 6f 67 67 65 72 } //01 00  EnableKeylogger
		$a_01_24 = {45 6e 61 62 6c 65 42 72 6f 77 73 65 72 52 65 63 6f 76 65 72 79 } //01 00  EnableBrowserRecovery
		$a_01_25 = {45 6e 61 62 6c 65 53 63 72 65 65 6e 73 68 6f 74 } //01 00  EnableScreenshot
		$a_01_26 = {45 6e 61 62 6c 65 46 6f 72 63 65 55 61 63 } //01 00  EnableForceUac
		$a_01_27 = {45 6e 61 62 6c 65 42 6f 74 4b 69 6c 6c 65 72 } //01 00  EnableBotKiller
		$a_01_28 = {45 6e 61 62 6c 65 44 65 6c 65 74 65 5a 6f 6e 65 49 64 65 6e 74 69 66 69 65 72 } //01 00  EnableDeleteZoneIdentifier
		$a_01_29 = {45 6e 61 62 6c 65 4d 65 6d 6f 72 79 53 63 61 6e } //01 00  EnableMemoryScan
		$a_01_30 = {45 6e 61 62 6c 65 41 6e 74 69 48 6f 6e 65 79 70 6f 74 } //01 00  EnableAntiHoneypot
		$a_01_31 = {45 6e 61 62 6c 65 4f 6e 6c 79 53 65 6e 64 57 68 65 6e 50 61 73 73 77 6f 72 64 } //01 00  EnableOnlySendWhenPassword
		$a_01_32 = {45 78 65 63 74 69 6f 6e 44 65 6c 61 79 } //01 00  ExectionDelay
		$a_01_33 = {53 65 6e 64 69 6e 67 49 6e 74 65 72 76 61 6c } //01 00  SendingInterval
		$a_01_34 = {45 6e 61 62 6c 65 44 6f 77 6e 6c 6f 61 64 65 72 } //01 00  EnableDownloader
		$a_01_35 = {44 6f 77 6e 6c 6f 61 64 65 72 55 72 6c } //01 00  DownloaderUrl
		$a_01_36 = {44 6f 77 6e 6c 6f 61 64 65 72 46 69 6c 65 6e 61 6d 65 } //01 00  DownloaderFilename
		$a_01_37 = {44 6f 77 6e 6c 6f 61 64 65 72 4f 6e 63 65 } //01 00  DownloaderOnce
		$a_01_38 = {45 6e 61 62 6c 65 42 69 6e 64 65 72 } //01 00  EnableBinder
		$a_01_39 = {42 69 6e 64 65 72 42 79 74 65 73 } //01 00  BinderBytes
		$a_01_40 = {42 69 6e 64 65 72 4e 61 6d 65 } //01 00  BinderName
		$a_01_41 = {42 69 6e 64 65 72 4f 6e 63 65 } //01 00  BinderOnce
		$a_01_42 = {45 6e 61 62 6c 65 49 6e 73 74 61 6c 6c } //01 00  EnableInstall
		$a_01_43 = {49 6e 73 74 61 6c 6c 46 6f 6c 64 65 72 } //01 00  InstallFolder
		$a_01_44 = {49 6e 73 74 61 6c 6c 53 65 63 6f 6e 64 46 6f 6c 64 65 72 } //01 00  InstallSecondFolder
		$a_01_45 = {49 6e 73 74 61 6c 6c 46 69 6c 65 } //01 00  InstallFile
		$a_01_46 = {53 65 61 72 63 68 41 6e 64 55 70 6c 6f 61 64 45 78 74 65 6e 73 69 6f 6e 73 } //01 00  SearchAndUploadExtensions
		$a_01_47 = {53 65 61 72 63 68 41 6e 64 55 70 6c 6f 61 64 53 69 7a 65 4c 69 6d 69 74 } //01 00  SearchAndUploadSizeLimit
		$a_01_48 = {53 65 61 72 63 68 41 6e 64 55 70 6c 6f 61 64 5a 69 70 53 69 7a 65 } //01 00  SearchAndUploadZipSize
		$a_01_49 = {45 6e 61 62 6c 65 57 69 6e 64 6f 77 53 65 61 72 63 68 65 72 } //01 00  EnableWindowSearcher
		$a_01_50 = {57 69 6e 64 6f 77 53 65 61 72 63 68 65 72 4b 65 79 77 6f 72 64 73 } //01 00  WindowSearcherKeywords
		$a_01_51 = {4d 61 69 6e 44 69 72 65 63 74 6f 72 79 } //01 00  MainDirectory
		$a_01_52 = {53 61 66 65 54 68 72 65 61 64 } //00 00  SafeThread
	condition:
		any of ($a_*)
 
}