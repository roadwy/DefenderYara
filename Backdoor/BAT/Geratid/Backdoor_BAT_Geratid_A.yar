
rule Backdoor_BAT_Geratid_A{
	meta:
		description = "Backdoor:BAT/Geratid.A,SIGNATURE_TYPE_PEHSTR_EXT,2c 00 2a 00 07 00 00 "
		
	strings :
		$a_01_0 = {33 36 30 2c 62 65 61 74 2c 64 77 32 30 2c 64 77 77 69 6e 2c 6b 61 76 2c 6d 61 6c 77 61 72 65 2c 6e 74 76 64 6d 2c 70 63 74 73 } //20 360,beat,dw20,dwwin,kav,malware,ntvdm,pcts
		$a_01_1 = {52 41 54 49 44 2e 53 65 74 49 64 65 6e 74 69 66 69 63 61 74 69 6f 6e 28 52 41 54 5f 4b 45 59 2c 20 6e 65 77 49 64 29 } //20 RATID.SetIdentification(RAT_KEY, newId)
		$a_01_2 = {68 65 6c 6d 6f 6c 61 6e 6e 61 64 75 72 69 2e 73 65 72 76 65 68 74 74 70 2e 63 6f 6d 2f 61 6e 6e 6f 75 6e 63 65 2f } //2 helmolannaduri.servehttp.com/announce/
		$a_01_3 = {68 77 69 64 3d 22 20 26 20 48 57 49 44 20 26 20 22 26 72 69 64 3d 22 20 26 20 52 41 54 49 44 20 26 20 22 26 72 6e 6f 3d 22 20 26 20 52 41 54 4e 4f } //2 hwid=" & HWID & "&rid=" & RATID & "&rno=" & RATNO
		$a_01_4 = {7b 22 4e 65 72 6f 43 68 65 63 6b 22 2c 20 22 6c 73 61 73 73 73 22 7d } //2 {"NeroCheck", "lsasss"}
		$a_01_5 = {49 44 73 2e 41 64 64 28 22 54 65 6e 63 65 6e 74 22 29 } //2 IDs.Add("Tencent")
		$a_01_6 = {28 4e 65 77 20 53 74 72 69 6e 67 28 29 7b 22 41 64 6f 62 65 41 52 4d 2e 65 78 65 22 7d 29 } //2 (New String(){"AdobeARM.exe"})
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*20+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=42
 
}