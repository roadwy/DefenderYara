
rule Trojan_Win32_Rugmi_HE_MTB{
	meta:
		description = "Trojan:Win32/Rugmi.HE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 0f be 04 30 66 89 04 72 46 a1 ?? ?? ?? ?? 80 3c 30 00 90 09 05 00 a1 90 1b 00 } //6
		$a_01_1 = {8b 42 3c 8b 5c 10 2c 8d } //1
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*1) >=7
 
}