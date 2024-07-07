
rule Trojan_Win32_Kilim_gen_B{
	meta:
		description = "Trojan:Win32/Kilim.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 41 5f 41 70 70 44 61 74 61 25 5c 69 6e 73 74 61 6c 6c 5f 66 6c 61 73 68 2e 65 78 65 } //1 %A_AppData%\install_flash.exe
		$a_01_1 = {44 6c 6c 43 61 6c 6c 28 53 68 65 6c 6c 45 78 65 63 75 74 65 2c 20 75 69 6e 74 2c 20 30 2c 20 73 74 72 2c 20 22 52 75 6e 41 73 22 } //1 DllCall(ShellExecute, uint, 0, str, "RunAs"
		$a_01_2 = {25 41 5f 41 70 70 64 61 74 61 25 5c 66 6c 61 73 68 2e 78 70 69 } //1 %A_Appdata%\flash.xpi
		$a_01_3 = {52 65 67 45 78 52 65 70 6c 61 63 65 28 59 61 6e 64 65 78 50 72 65 66 2c 20 22 5c 5c 5c 5c 54 77 61 69 6e 73 } //1 RegExReplace(YandexPref, "\\\\Twains
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}