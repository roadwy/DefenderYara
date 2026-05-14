
rule Trojan_Win64_Greedy_AH_MTB{
	meta:
		description = "Trojan:Win64/Greedy.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_01_0 = {5b 45 52 52 4f 52 5d 20 46 61 69 6c 65 64 20 74 6f 20 63 72 65 61 74 65 20 53 74 65 61 6c 2e 7a 69 70 2e } //30 [ERROR] Failed to create Steal.zip.
		$a_01_1 = {5b 49 4e 46 4f 5d 20 74 64 69 72 73 2e 74 78 74 20 6e 6f 74 20 66 6f 75 6e 64 2e 20 53 74 61 72 74 69 6e 67 20 64 65 65 70 20 66 6f 6c 64 65 72 20 73 65 61 72 63 68 2e 2e 2e } //20 [INFO] tdirs.txt not found. Starting deep folder search...
		$a_01_2 = {5b 44 4f 4e 45 5d 20 54 65 6d 70 6f 72 61 72 79 20 66 6f 6c 64 65 72 20 72 65 6d 6f 76 65 64 2e } //10 [DONE] Temporary folder removed.
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}