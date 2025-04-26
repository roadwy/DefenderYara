
rule Trojan_BAT_BypassUAC_NB_MTB{
	meta:
		description = "Trojan:BAT/BypassUAC.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 72 6f 6f 74 5c 53 65 63 75 72 69 74 79 43 65 6e 74 65 72 32 } //3 \root\SecurityCenter2
		$a_81_1 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //2 Select * from AntivirusProduct
		$a_81_2 = {57 65 62 45 79 65 2e 43 6f 6e 74 72 6f 6c 73 2e 57 69 6e 46 6f 72 6d 73 2e 57 65 62 43 61 6d 65 72 61 43 6f 6e 74 72 6f 6c 2e 64 6c 6c } //1 WebEye.Controls.WinForms.WebCameraControl.dll
		$a_81_3 = {2f 73 65 6e 64 2d 70 61 73 73 77 6f 72 64 73 } //1 /send-passwords
		$a_81_4 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 64 65 6c 65 74 65 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d } //1 netsh firewall delete allowedprogram
		$a_81_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_81_6 = {5a 54 5f 52 41 54 } //1 ZT_RAT
		$a_81_7 = {2f 67 65 74 2d 72 65 6d 6f 74 65 2d 73 68 65 6c 6c } //1 /get-remote-shell
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=11
 
}