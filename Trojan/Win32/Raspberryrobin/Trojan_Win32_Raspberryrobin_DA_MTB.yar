
rule Trojan_Win32_Raspberryrobin_DA_MTB{
	meta:
		description = "Trojan:Win32/Raspberryrobin.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 62 66 67 67 76 46 72 74 76 79 62 } //1 UbfggvFrtvyb
		$a_01_1 = {74 64 68 79 66 6a 67 79 2e 64 6c 6c } //1 tdhyfjgy.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}