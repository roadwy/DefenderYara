
rule Trojan_Win64_Vidar_AVD_MTB{
	meta:
		description = "Trojan:Win64/Vidar.AVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {42 8a 04 0a 44 30 c0 42 88 04 09 42 8a 04 0a 44 30 c0 42 88 04 09 83 3d 7e da 0b 00 0a 7c b5 } //3
		$a_01_1 = {41 8a 04 24 34 cb 88 05 bc 1b 08 00 41 8a 44 24 01 34 cb 88 05 b0 1b 08 00 c6 05 aa 1b 08 00 00 48 83 ec 20 ba 80 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}