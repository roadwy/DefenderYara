
rule Trojan_Win32_Cryptinject_RAC_MTB{
	meta:
		description = "Trojan:Win32/Cryptinject.RAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 73 3f 74 79 70 65 3d 32 26 68 61 73 68 3d 25 73 26 74 69 6d 65 3d 25 73 } //01 00  http://%s:%d/%s?type=2&hash=%s&time=%s
		$a_01_1 = {54 68 65 20 4e 43 42 45 4e 55 4d 20 72 65 74 75 72 6e 20 61 64 61 70 74 65 72 20 6e 75 6d 62 65 72 20 69 73 3a 20 25 64 } //01 00  The NCBENUM return adapter number is: %d
		$a_01_2 = {77 77 77 2e 79 61 6e 64 65 78 32 75 6e 69 74 65 64 73 74 61 74 65 64 2e 64 79 6e 61 6d 69 63 2d 64 6e 73 2e 6e 65 74 } //01 00  www.yandex2unitedstated.dynamic-dns.net
		$a_01_3 = {49 73 20 76 6d 77 61 72 65 } //00 00  Is vmware
	condition:
		any of ($a_*)
 
}