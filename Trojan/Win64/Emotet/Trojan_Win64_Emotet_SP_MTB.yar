
rule Trojan_Win64_Emotet_SP_MTB{
	meta:
		description = "Trojan:Win64/Emotet.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 bf 3c b6 22 49 8b ca 49 83 c1 01 49 83 c2 01 41 f7 e0 c1 ea 03 41 83 c0 01 8b c2 48 6b c0 3b 48 2b c8 0f b6 04 19 42 32 44 0e ff 44 3b c7 41 88 41 ff 72 cb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}