
rule Trojan_Win64_Bumblebee_FC_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.FC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f af c1 8b 4d f3 48 98 } //1
		$a_01_1 = {8b 45 fb 0b c8 29 4d 6f 8b 4d eb 8b 45 6f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}