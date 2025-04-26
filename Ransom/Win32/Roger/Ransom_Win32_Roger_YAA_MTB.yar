
rule Ransom_Win32_Roger_YAA_MTB{
	meta:
		description = "Ransom:Win32/Roger.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 7d 38 03 45 60 83 3d 28 53 4e 00 00 89 45 6c 75 06 ff 05 20 53 4e 00 32 c1 88 45 6b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}