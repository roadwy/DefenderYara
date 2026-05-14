
rule TrojanDownloader_Win64_Zusy_AHB_MTB{
	meta:
		description = "TrojanDownloader:Win64/Zusy.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_01_0 = {5b 2a 5d 20 4b 69 6c 6c 69 6e 67 20 50 72 6f 63 65 73 73 65 73 20 61 6e 64 20 44 65 6c 65 74 69 6e 67 20 46 69 6c 65 73 2e 2e } //30 [*] Killing Processes and Deleting Files..
		$a_01_1 = {69 30 35 20 65 78 69 73 74 2e 20 53 6c 65 65 70 69 6e 67 20 35 73 20 74 68 65 6e 20 65 78 69 74 69 6e 67 2e 2e 2e } //10 i05 exist. Sleeping 5s then exiting...
		$a_01_2 = {5b 2b 5d 20 44 6f 77 6e 6c 6f 61 64 65 64 20 65 6e 63 72 79 70 74 65 64 20 4a 53 4f 4e 20 28 25 6c 75 20 62 79 74 65 73 29 } //20 [+] Downloaded encrypted JSON (%lu bytes)
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*10+(#a_01_2  & 1)*20) >=60
 
}