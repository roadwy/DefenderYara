
rule Ransom_Win32_LockBit_AL_MTB{
	meta:
		description = "Ransom:Win32/LockBit.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 30 fa 80 70 0a fa 83 c0 14 39 f0 75 } //4
		$a_01_1 = {c7 04 24 10 27 00 00 ff d3 83 ec 04 eb } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}