
rule Trojan_Win32_OffLoader_GPF_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.GPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_80_0 = {74 68 72 6f 61 74 62 61 6c 61 6e 63 65 2e 78 79 7a 2f 72 65 61 70 2e 70 68 70 3f 70 65 } //throatbalance.xyz/reap.php?pe  5
		$a_80_1 = {73 6b 69 72 74 72 6f 73 65 2e 73 69 74 65 2f 74 72 61 63 6b 65 72 2f 74 68 61 6e 6b 5f 79 6f 75 2e 70 68 70 } //skirtrose.site/tracker/thank_you.php  2
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*2) >=7
 
}