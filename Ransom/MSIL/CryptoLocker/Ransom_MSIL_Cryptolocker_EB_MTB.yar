
rule Ransom_MSIL_Cryptolocker_EB_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {9a 0b 07 14 72 ?? ?? ?? 70 17 8d 03 00 00 01 13 ?? 11 ?? 16 72 ?? ?? ?? 70 a2 11 ?? 14 14 14 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 2c 02 2b 0b 07 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 11 ?? 17 d6 13 ?? 11 ?? 11 ?? 8e b7 32 b6 } //10
		$a_81_1 = {2e 61 72 6d 79 } //1 .army
		$a_81_2 = {2e 61 72 73 69 75 6d } //1 .arsium
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=11
 
}