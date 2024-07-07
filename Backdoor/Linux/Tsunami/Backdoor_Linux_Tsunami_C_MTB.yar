
rule Backdoor_Linux_Tsunami_C_MTB{
	meta:
		description = "Backdoor:Linux/Tsunami.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_00_0 = {73 68 69 74 2e 70 68 70 3f 69 64 3d 3e 20 3c 47 45 54 2f 48 45 41 44 2f 50 4f 53 54 3e 20 3d 20 48 54 54 50 20 66 6c 6f 6f 64 } //1 shit.php?id=> <GET/HEAD/POST> = HTTP flood
		$a_00_1 = {41 6e 6f 74 68 65 72 20 6e 6f 6e 2d 73 70 6f 6f 66 20 75 64 70 20 66 6c 6f 6f 64 65 72 } //1 Another non-spoof udp flooder
		$a_00_2 = {44 6f 77 6e 6c 6f 61 64 73 20 61 20 66 69 6c 65 20 6f 66 66 20 74 68 65 20 77 65 62 20 61 6e 64 20 73 61 76 65 73 20 69 74 20 6f 6e 74 6f 20 74 68 65 20 68 64 } //1 Downloads a file off the web and saves it onto the hd
		$a_00_3 = {63 72 6f 6e 74 61 62 20 2d 6c 20 7c 20 67 72 65 70 20 25 73 20 7c 20 67 72 65 70 20 2d 76 } //1 crontab -l | grep %s | grep -v
		$a_00_4 = {4b 69 6c 6c 69 6e 67 20 70 69 64 } //1 Killing pid
		$a_00_5 = {61 64 76 61 6e 63 65 64 20 73 79 6e 20 66 6c 6f 6f 64 65 72 20 74 68 61 74 20 77 69 6c 6c 20 6b 69 6c 6c 20 6d 6f 73 74 20 6e 65 74 77 6f 72 6b } //1 advanced syn flooder that will kill most network
		$a_00_6 = {4b 69 6c 6c 73 20 61 6c 6c 20 63 75 72 72 65 6e 74 20 70 61 63 6b 65 74 69 6e 67 } //1 Kills all current packeting
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=3
 
}