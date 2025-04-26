
rule Backdoor_MacOS_Tusnami_A_MTB{
	meta:
		description = "Backdoor:MacOS/Tusnami.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {3a 54 53 55 4e 41 4d 49 20 3c 74 61 72 67 65 74 3e 20 3c 73 65 63 73 3e } //1 :TSUNAMI <target> <secs>
		$a_00_1 = {73 79 6e 20 66 6c 6f 6f 64 65 72 20 74 68 61 74 20 77 69 6c 6c 20 6b 69 6c 6c 20 6d 6f 73 74 20 6e 65 74 77 6f 72 6b 20 64 72 69 76 65 72 73 } //1 syn flooder that will kill most network drivers
		$a_00_2 = {4b 69 6c 6c 69 6e 67 20 70 69 64 20 25 64 } //1 Killing pid %d
		$a_00_3 = {44 6f 77 6e 6c 6f 61 64 73 20 61 20 66 69 6c 65 20 6f 66 66 20 74 68 65 20 77 65 62 20 61 6e 64 20 73 61 76 65 73 20 69 74 20 6f 6e 74 6f 20 74 68 65 20 68 64 } //1 Downloads a file off the web and saves it onto the hd
		$a_00_4 = {4b 69 6c 6c 73 20 61 6c 6c 20 63 75 72 72 65 6e 74 20 70 61 63 6b 65 74 69 6e 67 } //1 Kills all current packeting
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}