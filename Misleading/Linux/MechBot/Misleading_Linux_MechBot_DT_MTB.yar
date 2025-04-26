
rule Misleading_Linux_MechBot_DT_MTB{
	meta:
		description = "Misleading:Linux/MechBot.DT!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 75 73 72 2f 62 69 6e 2f 6b 69 6c 6c 61 6c 6c 20 2d 39 20 73 74 65 61 6c 74 68 } //1 /usr/bin/killall -9 stealth
		$a_01_1 = {73 74 65 61 6c 74 68 20 3c 69 70 2f 68 6f 73 74 6e 61 6d 65 3e } //1 stealth <ip/hostname>
		$a_01_2 = {43 4e 5f 42 4f 54 44 49 45 } //1 CN_BOTDIE
		$a_01_3 = {28 6d 65 63 68 5f 65 78 65 63 29 20 65 78 65 63 75 74 61 62 6c 65 20 68 61 73 20 62 65 65 6e 20 61 6c 74 65 72 65 64 } //1 (mech_exec) executable has been altered
		$a_01_4 = {28 6d 65 63 68 5f 65 78 65 63 29 20 75 6e 61 62 6c 65 20 74 6f 20 73 74 61 74 20 65 78 65 63 75 74 61 62 6c 65 } //1 (mech_exec) unable to stat executable
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}