
rule Trojan_Win32_Raspberryrobin_DA_MTB{
	meta:
		description = "Trojan:Win32/Raspberryrobin.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 62 66 67 67 76 46 72 74 76 79 62 } //01 00  UbfggvFrtvyb
		$a_01_1 = {74 64 68 79 66 6a 67 79 2e 64 6c 6c } //00 00  tdhyfjgy.dll
	condition:
		any of ($a_*)
 
}