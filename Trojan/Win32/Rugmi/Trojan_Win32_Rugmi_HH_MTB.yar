
rule Trojan_Win32_Rugmi_HH_MTB{
	meta:
		description = "Trojan:Win32/Rugmi.HH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_23_0 = {8b ec 81 ec 90 01 03 00 c7 45 90 02 50 5c 90 02 50 83 90 01 01 01 90 02 a0 6a 00 6a 00 6a 00 6a 00 90 02 20 ff 55 90 00 01 } //6
		$a_83_1 = {f8 00 74 } //3840
	condition:
		((#a_23_0  & 1)*6+(#a_83_1  & 1)*3840) >=7
 
}