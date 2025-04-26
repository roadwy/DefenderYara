
rule Virus_Win32_Virut_HNE_MTB{
	meta:
		description = "Virus:Win32/Virut.HNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {a2 b0 80 f2 cf dc 71 ce 2b 86 68 8f ac 33 78 aa } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}