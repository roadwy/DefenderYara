
rule Worm_Win32_Brontok_MBQ_MTB{
	meta:
		description = "Worm:Win32/Brontok.MBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {70 7f 40 00 00 f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 00 7a 40 00 e8 78 40 00 00 20 40 00 78 00 00 00 7d 00 00 00 82 00 00 00 83 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}