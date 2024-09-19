
rule Trojan_Win64_Bitser_NB_MTB{
	meta:
		description = "Trojan:Win64/Bitser.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 31 c0 50 48 8b 4c 24 48 48 83 ec 28 e8 ?? ?? ?? ?? 48 83 c4 28 48 8b 4c 24 40 48 83 ec 28 e8 ?? ?? ?? ?? 48 83 c4 28 48 8b 4c 24 50 48 83 ec 28 e8 ?? ?? ?? ?? 48 83 c4 28 } //3
		$a_01_1 = {6e 69 7a 68 65 6e 65 74 73 2e 63 6f 6d } //1 nizhenets.com
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}