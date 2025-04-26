
rule Trojan_Win32_BHO_EH{
	meta:
		description = "Trojan:Win32/BHO.EH,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 73 70 79 2d 6b 69 6c 6c 2e 63 6f 6d 2f 62 68 6f 5f 61 64 75 6c 74 2e 74 78 74 } //4 http://spy-kill.com/bho_adult.txt
		$a_01_1 = {44 3a 5c 41 70 70 5c 44 65 6c 70 68 69 37 5c 53 6f 75 72 63 65 20 43 6f 64 65 5c 41 64 77 61 72 65 5c 5f 49 45 42 72 6f 77 73 65 72 48 65 6c 70 65 72 2e 70 61 73 } //5 D:\App\Delphi7\Source Code\Adware\_IEBrowserHelper.pas
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*5) >=9
 
}