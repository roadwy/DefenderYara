
rule Spammer_Win32_Hedsen_C{
	meta:
		description = "Spammer:Win32/Hedsen.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 61 63 74 69 6f 6e 2e 70 68 70 3f 61 63 74 69 6f 6e 3d 67 65 74 5f 6d 61 69 6c 73 } //01 00  /action.php?action=get_mails
		$a_01_1 = {3c 64 62 20 66 69 6c 65 3e 20 3c 64 6f 6d 61 69 6e 3e 20 3c 75 73 65 72 3e 20 3c 74 65 6d 70 6c 61 74 65 20 66 69 6c 65 3e 20 3c 72 65 73 75 6d 65 20 6c 69 6e 65 20 6e 75 6d 62 65 72 20 6f 70 74 69 6f 6e 61 6c 3e } //01 00  <db file> <domain> <user> <template file> <resume line number optional>
		$a_01_2 = {2f 61 63 74 69 6f 6e 2e 70 68 70 3f 61 63 74 69 6f 6e 3d 67 65 74 5f 72 65 64 } //01 00  /action.php?action=get_red
		$a_01_3 = {73 65 6e 74 5f 61 6c 6c 3d 25 75 26 73 65 6e 74 5f 73 75 63 63 65 73 73 3d 25 75 26 61 63 74 69 76 65 5f 63 6f 6e 6e 65 63 74 69 6f 6e 73 3d 25 75 26 71 75 65 75 65 5f 63 6f 6e 6e 65 63 74 69 6f 6e 73 3d 25 75 } //01 00  sent_all=%u&sent_success=%u&active_connections=%u&queue_connections=%u
		$a_00_4 = {6d 61 69 6c 20 66 72 6f 6d 3a 3c } //01 00  mail from:<
		$a_01_5 = {3c 24 75 73 65 72 24 40 24 64 6f 6d 61 69 6e 24 3e 3b 20 24 73 65 72 76 65 72 44 61 74 65 24 } //01 00  <$user$@$domain$>; $serverDate$
		$a_01_6 = {62 79 20 24 64 6f 6d 61 69 6e 24 20 28 50 6f 73 74 66 69 78 29 } //00 00  by $domain$ (Postfix)
		$a_00_7 = {87 10 } //00 00 
	condition:
		any of ($a_*)
 
}