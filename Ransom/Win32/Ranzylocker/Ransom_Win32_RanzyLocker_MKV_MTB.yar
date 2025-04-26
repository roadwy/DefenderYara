
rule Ransom_Win32_RanzyLocker_MKV_MTB{
	meta:
		description = "Ransom:Win32/RanzyLocker.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 8b 5d 08 83 79 14 10 8b d1 72 ?? 8b 11 30 1c 02 40 3b c6 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}