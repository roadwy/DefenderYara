
rule Trojan_Win32_Sopus_B{
	meta:
		description = "Trojan:Win32/Sopus.B,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 15 00 00 0a 00 "
		
	strings :
		$a_01_0 = {68 0b f6 1f cb 6a 0a e8 } //0a 00 
		$a_01_1 = {68 95 5b 28 03 6a 01 e8 } //0a 00 
		$a_01_2 = {68 20 5d 35 5b 6a 0a e8 } //0a 00 
		$a_01_3 = {68 23 27 a5 91 6a 06 e8 } //01 00 
		$a_01_4 = {61 6c 6f 72 73 2e 64 65 65 70 64 6e 73 2e 63 72 79 70 74 6f 73 74 6f 72 6d 2e 6e 65 74 } //01 00  alors.deepdns.cryptostorm.net
		$a_01_5 = {61 6e 79 6f 6e 65 2e 64 6e 73 72 65 63 2e 6d 65 6f 2e 77 73 } //01 00  anyone.dnsrec.meo.ws
		$a_01_6 = {61 6e 79 74 77 6f 2e 64 6e 73 72 65 63 2e 6d 65 6f 2e 77 73 } //01 00  anytwo.dnsrec.meo.ws
		$a_01_7 = {63 69 76 65 74 2e 7a 69 70 68 61 7a 65 2e 63 6f 6d } //01 00  civet.ziphaze.com
		$a_01_8 = {69 73 74 2e 66 65 6c 6c 69 67 2e 6f 72 67 } //01 00  ist.fellig.org
		$a_01_9 = {6e 73 2e 64 6f 74 62 69 74 2e 6d 65 } //01 00  ns.dotbit.me
		$a_01_10 = {6e 73 31 2e 61 6e 79 2e 64 6e 73 2e 64 30 77 6e 2e 62 69 7a } //01 00  ns1.any.dns.d0wn.biz
		$a_01_11 = {6e 73 31 2e 64 6f 6d 61 69 6e 63 6f 69 6e 2e 6e 65 74 } //01 00  ns1.domaincoin.net
		$a_01_12 = {6e 73 31 2e 6e 6c 2e 64 6e 73 2e 64 30 77 6e 2e 62 69 7a } //01 00  ns1.nl.dns.d0wn.biz
		$a_01_13 = {6e 73 31 2e 72 61 6e 64 6f 6d 2e 64 6e 73 2e 64 30 77 6e 2e 62 69 7a } //01 00  ns1.random.dns.d0wn.biz
		$a_01_14 = {6e 73 31 2e 73 67 2e 64 6e 73 2e 64 30 77 6e 2e 62 69 7a } //01 00  ns1.sg.dns.d0wn.biz
		$a_01_15 = {6e 73 31 2e 73 6f 75 72 70 75 73 73 2e 6e 65 74 } //01 00  ns1.sourpuss.net
		$a_01_16 = {6e 73 31 2e 73 79 64 2e 64 6e 73 2e 6c 63 68 69 2e 6d 70 } //01 00  ns1.syd.dns.lchi.mp
		$a_01_17 = {6e 73 32 2e 64 6f 6d 61 69 6e 63 6f 69 6e 2e 6e 65 74 } //01 00  ns2.domaincoin.net
		$a_01_18 = {6e 73 32 2e 66 72 2e 64 6e 73 2e 64 30 77 6e 2e 62 69 7a } //01 00  ns2.fr.dns.d0wn.biz
		$a_01_19 = {6e 73 32 2e 72 61 6e 64 6f 6d 2e 64 6e 73 2e 64 30 77 6e 2e 62 69 7a } //01 00  ns2.random.dns.d0wn.biz
		$a_01_20 = {6f 6e 79 78 2e 64 65 65 70 64 6e 73 2e 63 72 79 70 74 6f 73 74 6f 72 6d 2e 6e 65 74 } //00 00  onyx.deepdns.cryptostorm.net
		$a_00_21 = {5d 04 00 00 48 a8 03 80 5c 2f 00 00 49 a8 03 80 00 00 01 00 22 00 19 00 48 61 63 6b 54 6f 6f 6c 3a 57 69 6e 36 34 2f 4d } //69 6d 
	condition:
		any of ($a_*)
 
}