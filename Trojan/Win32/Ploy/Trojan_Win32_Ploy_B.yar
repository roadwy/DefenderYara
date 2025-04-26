
rule Trojan_Win32_Ploy_B{
	meta:
		description = "Trojan:Win32/Ploy.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 4b 65 79 6d 79 63 79 } //1 .Keymycy
		$a_01_1 = {55 4d 49 2e 64 6c 6c } //1 UMI.dll
		$a_01_2 = {68 74 74 70 3a 2f 2f 6b 65 79 6d 79 63 79 76 69 70 2e 75 75 65 61 73 79 2e 63 6f 6d 2f } //1 http://keymycyvip.uueasy.com/
		$a_01_3 = {5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 \shell\open\command
		$a_01_4 = {5c 55 4d 49 2e 49 4e 49 } //1 \UMI.INI
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}