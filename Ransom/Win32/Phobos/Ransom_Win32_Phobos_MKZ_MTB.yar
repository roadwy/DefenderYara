
rule Ransom_Win32_Phobos_MKZ_MTB{
	meta:
		description = "Ransom:Win32/Phobos.MKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 7d 10 8d 58 ff c1 eb 04 43 8b 45 10 8b ce 2b c8 c7 45 ?? 10 00 00 00 8a 14 07 32 10 88 14 01 40 ff 4d fc 75 ?? 83 7d 0c 01 ff 75 08 8b c6 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}