
rule Ransom_MSIL_JigsawLocker_PA_MTB{
	meta:
		description = "Ransom:MSIL/JigsawLocker.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 69 74 63 6f 69 6e 53 74 65 61 6c 65 72 2e 65 78 65 } //1 BitcoinStealer.exe
		$a_02_1 = {fe 0c 00 00 20 00 00 00 00 fe 0c 00 00 20 00 00 00 00 95 fe 0c 01 00 20 00 00 00 00 95 61 20 ?? ?? ?? ?? ?? 9e fe 0c 00 00 20 01 00 00 00 fe 0c 00 00 20 01 00 00 00 95 fe 0c 01 00 20 01 00 00 00 95 58 20 ?? ?? ?? ?? 61 9e fe 0c 00 00 20 02 00 00 00 fe 0c 00 00 20 02 00 00 00 95 fe 0c 01 00 20 02 00 00 00 95 } //1
		$a_02_2 = {fe 0c 08 00 fe 0c 0a 00 8f ?? 00 00 01 25 71 ?? 00 00 01 fe 0c 02 00 d2 61 d2 81 ?? 00 00 01 fe 0c 0a 00 20 ff 00 00 00 5f 3a 14 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}