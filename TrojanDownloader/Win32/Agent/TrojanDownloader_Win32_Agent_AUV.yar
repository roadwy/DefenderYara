
rule TrojanDownloader_Win32_Agent_AUV{
	meta:
		description = "TrojanDownloader:Win32/Agent.AUV,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 64 69 73 74 2e 63 68 65 63 6b 69 6e 31 30 30 2e 63 6f 6d 2f 63 6f 6d 6d 61 6e 64 3f 70 72 6f 6a 65 63 74 49 44 3d 25 73 26 61 66 66 69 6c 69 61 74 65 49 44 3d 25 73 26 63 61 6d 70 61 69 67 6e 49 44 3d 25 73 26 61 70 70 6c 69 63 61 74 69 6f 6e 3d 25 73 26 76 3d 39 } //1 http://dist.checkin100.com/command?projectID=%s&affiliateID=%s&campaignID=%s&application=%s&v=9
		$a_01_1 = {68 74 74 70 3a 2f 2f 73 65 6e 73 65 2d 73 75 70 65 72 2e 63 6f 6d 2f 63 67 69 2f 65 78 65 63 75 74 65 5f 6c 6f 67 2e 63 67 69 3f 66 69 6c 65 6e 61 6d 65 3d 64 65 62 75 67 26 74 79 70 65 3d 66 61 69 6c 65 64 5f 72 65 67 69 73 74 72 79 5f 72 65 61 64 } //1 http://sense-super.com/cgi/execute_log.cgi?filename=debug&type=failed_registry_read
		$a_01_2 = {68 74 74 70 3a 2f 2f 63 6c 69 65 6e 74 2e 6d 79 61 64 75 6c 74 65 78 70 6c 6f 72 65 72 2e 63 6f 6d 2f 62 75 6e 64 6c 65 5f 72 65 70 6f 72 74 2e 63 67 69 3f 76 3d 31 30 26 63 61 6d 70 61 69 67 6e 49 44 3d 25 73 26 6d 65 73 73 61 67 65 3d 25 73 } //1 http://client.myadultexplorer.com/bundle_report.cgi?v=10&campaignID=%s&message=%s
		$a_00_3 = {25 73 5c 74 65 73 74 5f 66 69 6c 65 31 32 33 34 2e 74 78 74 } //1 %s\test_file1234.txt
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4c 69 66 65 54 69 6d 65 50 6f 72 6e } //1 Software\LifeTimePorn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}