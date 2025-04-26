
rule Trojan_Win32_AntiAV_SP_MTB{
	meta:
		description = "Trojan:Win32/AntiAV.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 4c 47 42 43 41 4f 2e } //1 MLGBCAO.
		$a_01_1 = {61 6d 64 6b 38 44 65 76 69 63 65 } //1 amdk8Device
		$a_01_2 = {63 63 74 65 31 73 74 6f } //1 ccte1sto
		$a_01_3 = {61 6d 64 6b 38 2e 64 6c 6c } //1 amdk8.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}