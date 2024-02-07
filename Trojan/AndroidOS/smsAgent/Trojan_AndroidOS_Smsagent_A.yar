
rule Trojan_AndroidOS_Smsagent_A{
	meta:
		description = "Trojan:AndroidOS/Smsagent.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 61 66 66 6d 6f 62 2e 74 6f 72 6e 69 6b 61 2e 63 6f 6d 2f 73 65 72 76 69 63 65 5f 6c 69 62 2e 70 68 70 } //01 00  http://affmob.tornika.com/service_lib.php
		$a_01_1 = {63 6f 6d 2e 62 6a 6f 65 61 6a 66 70 61 } //01 00  com.bjoeajfpa
		$a_01_2 = {73 79 73 5f 73 65 6e 64 5f 63 6f 6e 74 65 6e 74 73 } //01 00  sys_send_contents
		$a_01_3 = {54 4e 4b 4c 49 42 20 7c 7c 7c 20 53 54 41 52 54 49 4e 47 20 53 45 52 56 49 43 45 } //00 00  TNKLIB ||| STARTING SERVICE
	condition:
		any of ($a_*)
 
}