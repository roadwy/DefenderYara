
rule Ransom_Win32_CoranaLock_SK_MTB{
	meta:
		description = "Ransom:Win32/CoranaLock.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 89 2c e4 29 ed 09 c5 89 ab ?? ?? ?? ?? 5d 81 e0 00 00 00 00 33 04 e4 83 ec fc ff e0 83 bb ?? ?? ?? ?? 00 75 16 ff 93 } //2
		$a_02_1 = {31 fa 5f 6a 08 8f 45 fc d1 c0 8a fc 8a e6 d1 cb ff 4d fc 75 ?? 53 8f 45 f8 ff 75 f8 58 aa 49 75 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}