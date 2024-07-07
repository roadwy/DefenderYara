
rule Ransom_Win32_Weelsof_E{
	meta:
		description = "Ransom:Win32/Weelsof.E,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3c 21 2d 2d 20 24 5f 4e 4f 54 49 43 45 5f 42 4c 4f 43 4b 5f 25 64 5f 53 54 41 52 54 5f 24 20 2d 2d 3e } //1 <!-- $_NOTICE_BLOCK_%d_START_$ -->
		$a_01_1 = {2f 67 65 74 5f 64 73 6e 2e 70 68 70 } //1 /get_dsn.php
		$a_01_2 = {24 5f 49 50 5f 41 44 44 52 5f 24 } //1 $_IP_ADDR_$
		$a_01_3 = {6a 00 68 00 f7 0c 84 6a 00 6a 00 6a 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}