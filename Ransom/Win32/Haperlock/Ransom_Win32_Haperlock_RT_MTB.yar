
rule Ransom_Win32_Haperlock_RT_MTB{
	meta:
		description = "Ransom:Win32/Haperlock.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 9c 8d dc fb ff ff 89 9c 95 dc fb ff ff 89 b4 8d dc fb ff ff 01 f3 0f b6 db 8b 9c 9d dc fb ff ff 8b bd d0 fb ff ff 30 1c 07 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}