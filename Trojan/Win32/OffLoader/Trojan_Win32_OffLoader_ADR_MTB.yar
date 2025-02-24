
rule Trojan_Win32_OffLoader_ADR_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.ADR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 00 6e 00 63 00 72 00 65 00 61 00 73 00 65 00 67 00 72 00 61 00 6e 00 64 00 6d 00 6f 00 74 00 68 00 65 00 72 00 2e 00 78 00 79 00 7a 00 2f 00 74 00 72 00 75 00 2e 00 70 00 68 00 70 00 3f 00 70 00 65 00 } //3 increasegrandmother.xyz/tru.php?pe
		$a_01_1 = {67 00 72 00 61 00 70 00 65 00 63 00 75 00 62 00 2e 00 73 00 62 00 73 00 2f 00 74 00 72 00 6d 00 2e 00 70 00 68 00 70 00 3f 00 70 00 65 00 } //3 grapecub.sbs/trm.php?pe
		$a_01_2 = {2f 00 6e 00 6f 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 } //1 /nocookies
		$a_01_3 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } //1 /silent
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}