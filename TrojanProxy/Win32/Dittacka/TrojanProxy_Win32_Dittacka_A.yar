
rule TrojanProxy_Win32_Dittacka_A{
	meta:
		description = "TrojanProxy:Win32/Dittacka.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 01 00 "
		
	strings :
		$a_80_0 = {73 6f 63 6b 73 5c 53 6f 63 6b 73 4d 67 72 2e 63 70 70 } //socks\SocksMgr.cpp  01 00 
		$a_80_1 = {73 6f 63 6b 73 5c 53 6f 63 6b 73 50 61 72 73 65 72 2e 63 70 70 } //socks\SocksParser.cpp  01 00 
		$a_80_2 = {50 72 6f 78 79 20 45 72 72 6f 72 21 } //Proxy Error!  01 00 
		$a_80_3 = {51 55 45 52 59 20 44 4e 53 20 45 72 72 6f 72 } //QUERY DNS Error  02 00 
		$a_80_4 = {54 75 6e 6e 65 6c 20 74 68 72 65 61 64 20 66 69 6e 69 73 68 21 } //Tunnel thread finish!  02 00 
		$a_80_5 = {41 63 63 65 70 74 20 66 61 69 6c 64 21 } //Accept faild!  02 00 
		$a_80_6 = {42 69 6e 64 20 25 64 20 66 61 69 6c 64 21 } //Bind %d faild!  02 00 
		$a_80_7 = {64 69 73 69 72 65 20 44 6f 6d 61 69 6e 4e 61 6d 65 20 3a 20 25 73 } //disire DomainName : %s  02 00 
		$a_80_8 = {64 65 73 74 69 6e 61 74 69 6f 6e 20 70 6f 72 74 20 3a 20 25 64 } //destination port : %d  03 00 
		$a_01_9 = {73 79 73 74 65 6d 00 00 5b 00 44 00 5d 00 00 00 5b 00 2b 00 5d 00 00 00 5b 00 2d 00 5d 00 00 00 5b 00 3f 00 5d 00 00 00 25 00 73 00 20 00 00 00 } //02 00 
		$a_03_10 = {66 0f d6 45 90 01 01 66 0f d6 45 90 01 01 ff 15 90 01 04 66 89 45 90 01 01 b8 02 00 00 00 6a 00 66 89 45 90 01 01 ff 15 90 01 04 6a 04 89 45 90 01 01 8d 45 90 01 01 50 6a 04 68 ff ff 00 00 90 00 } //00 00 
		$a_00_11 = {5d 04 00 00 fa b9 03 80 } //5c 29 
	condition:
		any of ($a_*)
 
}