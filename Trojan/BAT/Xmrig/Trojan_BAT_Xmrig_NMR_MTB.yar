
rule Trojan_BAT_Xmrig_NMR_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.NMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {58 13 06 11 0c 1f 18 64 d2 9c 09 11 0b 8f ?? ?? ?? 01 25 4b 11 0c 61 54 11 0d 20 ?? ?? ?? 00 5a 20 e3 08 f9 74 61 } //5
		$a_01_1 = {4a 49 54 53 74 61 72 74 65 72 } //1 JITStarter
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}