
rule Ransom_Win64_Ransomhub_B{
	meta:
		description = "Ransom:Win64/Ransomhub.B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 69 6c 6c 53 65 72 76 69 63 65 73 20 62 6f 6f 6c 20 22 6a 73 6f 6e 3a 5c 22 6b 69 6c 6c 5f 73 65 72 76 69 63 65 73 5c 22 22 3b 20 53 65 74 57 61 6c 6c 70 61 70 65 72 20 62 6f 6f 6c 20 22 6a 73 6f 6e 3a 5c 22 73 65 74 5f 77 61 6c 6c 70 61 70 65 72 5c 22 22 3b } //1 KillServices bool "json:\"kill_services\""; SetWallpaper bool "json:\"set_wallpaper\"";
		$a_01_1 = {53 65 6c 66 44 65 6c 65 74 65 20 62 6f 6f 6c 20 22 6a 73 6f 6e 3a 5c 22 73 65 6c 66 5f 64 65 6c 65 74 65 5c 22 22 3b 20 52 75 6e 6e 69 6e 67 4f 6e 65 20 62 6f 6f 6c 20 22 6a 73 6f 6e 3a 5c 22 72 75 6e 6e 69 6e 67 5f 6f 6e 65 5c 22 22 } //1 SelfDelete bool "json:\"self_delete\""; RunningOne bool "json:\"running_one\""
		$a_01_2 = {4c 6f 63 61 6c 44 69 73 6b 73 20 62 6f 6f 6c 20 22 6a 73 6f 6e 3a 5c 22 6c 6f 63 61 6c 5f 64 69 73 6b 73 5c 22 22 3b 20 4e 65 74 77 6f 72 6b 53 68 61 72 65 73 20 62 6f 6f 6c 20 22 6a 73 6f 6e 3a 5c 22 6e 65 74 77 6f 72 6b 5f 73 68 61 72 65 73 5c 22 22 3b } //1 LocalDisks bool "json:\"local_disks\""; NetworkShares bool "json:\"network_shares\"";
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}