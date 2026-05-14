
rule Trojan_Win32_Neoreblamy_NUM_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NUM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 fc 40 89 45 fc 83 7d fc 02 7d 10 8b 45 fc } //1
		$a_01_1 = {6a 0c 58 6b c0 00 8d 84 05 64 fd ff ff 6a 04 59 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}