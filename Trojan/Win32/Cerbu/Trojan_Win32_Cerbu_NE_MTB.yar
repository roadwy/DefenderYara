
rule Trojan_Win32_Cerbu_NE_MTB{
	meta:
		description = "Trojan:Win32/Cerbu.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {7c b4 33 db 8b 0d 90 01 04 8d 04 db 83 3c 81 90 01 01 8d 34 81 75 4d 85 db 90 00 } //5
		$a_01_1 = {66 75 79 75 6e 78 73 68 75 6f } //1 fuyunxshuo
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}