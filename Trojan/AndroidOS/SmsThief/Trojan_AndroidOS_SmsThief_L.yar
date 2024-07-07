
rule Trojan_AndroidOS_SmsThief_L{
	meta:
		description = "Trojan:AndroidOS/SmsThief.L,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {74 72 74 78 74 72 61 2e 63 6f 6d 2f 73 } //2 trtxtra.com/s
		$a_00_1 = {64 6f 6c 70 68 69 6e 5f 75 69 64 2e 74 78 74 } //2 dolphin_uid.txt
		$a_00_2 = {54 55 52 42 64 30 31 45 51 58 64 4e 52 45 46 33 54 55 67 33 54 47 52 48 54 51 2f 69 6e 64 65 78 2e 70 68 70 } //2 TURBd01EQXdNREF3TUg3TGRHTQ/index.php
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}