
rule Trojan_Win32_NetSeal_A_ibt{
	meta:
		description = "Trojan:Win32/NetSeal.A!ibt,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 65 00 61 00 6c 00 2e 00 65 00 6c 00 69 00 74 00 65 00 76 00 73 00 2e 00 6e 00 65 00 74 00 2f 00 42 00 61 00 73 00 65 00 } //1 http://seal.elitevs.net/Base
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 65 00 61 00 6c 00 2e 00 6e 00 69 00 6d 00 6f 00 72 00 75 00 2e 00 63 00 6f 00 6d 00 2f 00 42 00 61 00 73 00 65 00 2f 00 } //1 http://seal.nimoru.com/Base/
		$a_01_2 = {42 00 67 00 49 00 41 00 41 00 41 00 41 00 69 00 41 00 41 00 42 00 45 00 55 00 31 00 4d 00 78 00 41 00 41 00 51 00 41 00 41 00 4b 00 56 00 6c 00 75 00 72 00 64 00 5a 00 4d 00 61 00 48 00 79 00 } //1 BgIAAAAiAABEU1MxAAQAAKVlurdZMaHy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}