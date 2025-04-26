
rule Virus_Win32_Virut_AI{
	meta:
		description = "Virus:Win32/Virut.AI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {85 c0 75 09 cd 2e c1 e0 1f 79 1d } //1
		$a_03_1 = {55 b8 00 40 00 00 2b c9 ff 74 24 04 5d f7 d9 81 6c 24 04 ?? ?? ?? ?? 8d 84 01 80 fe ff ff 81 ed 06 10 30 00 85 c0 79 ae } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}