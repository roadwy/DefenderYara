
rule Trojan_Win32_Fauppod_SCPP_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.SCPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 61 73 74 6c 61 64 72 74 43 65 79 6e 74 62 } //2 RastladrtCeyntb
		$a_01_1 = {6b 65 65 76 65 6c 38 35 2e 64 6c 6c } //1 keevel85.dll
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}