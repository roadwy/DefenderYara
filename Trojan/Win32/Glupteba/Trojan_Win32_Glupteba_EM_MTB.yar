
rule Trojan_Win32_Glupteba_EM_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {4b 81 eb 01 00 00 00 31 32 42 09 df 68 0f dd 4e 8c 5f 39 c2 75 dd } //05 00 
		$a_01_1 = {8d 04 18 81 e9 01 00 00 00 41 8b 00 29 cf 57 59 81 e0 ff 00 00 00 51 5f 09 f9 43 89 ff 81 fb f4 01 00 00 75 05 } //00 00 
	condition:
		any of ($a_*)
 
}