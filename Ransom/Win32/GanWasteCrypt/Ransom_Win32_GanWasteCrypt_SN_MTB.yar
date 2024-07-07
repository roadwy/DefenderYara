
rule Ransom_Win32_GanWasteCrypt_SN_MTB{
	meta:
		description = "Ransom:Win32/GanWasteCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 11 89 15 90 01 04 8b 0d 90 01 04 a1 90 01 04 a3 90 01 03 00 90 08 00 04 a1 90 01 04 31 0d 90 01 04 a1 90 01 04 bb 90 00 } //2
		$a_02_1 = {55 8b ec 53 8b 25 90 01 03 00 58 8b e8 ff 35 90 01 03 00 ff 35 90 01 03 00 8b 1d 90 01 03 00 ff e3 5b 5d c3 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}