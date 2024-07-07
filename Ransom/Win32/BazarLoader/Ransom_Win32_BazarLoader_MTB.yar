
rule Ransom_Win32_BazarLoader_MTB{
	meta:
		description = "Ransom:Win32/BazarLoader!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c9 8a 84 0d 3b ff ff ff 0f b6 c0 83 e8 60 8d 04 c0 99 f7 fb 8d 42 7f 99 f7 fb 88 94 0d 3b ff ff ff 41 83 f9 52 72 da 6a 00 8d 85 34 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}