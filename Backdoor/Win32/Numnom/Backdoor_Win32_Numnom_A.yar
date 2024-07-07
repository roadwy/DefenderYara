
rule Backdoor_Win32_Numnom_A{
	meta:
		description = "Backdoor:Win32/Numnom.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0c 00 00 "
		
	strings :
		$a_01_0 = {50 6f 72 74 3e 25 69 3c 2f 4e 65 77 45 78 74 65 72 6e 61 6c } //1 Port>%i</NewExternal
		$a_01_1 = {2a 75 70 64 61 74 65 20 22 } //1 *update "
		$a_01_2 = {64 6f 77 6e 6c 6f 61 64 65 64 20 74 6f 3a 20 3c 25 73 3e } //1 downloaded to: <%s>
		$a_01_3 = {53 52 56 3a 20 72 69 70 3f 20 25 69 } //1 SRV: rip? %i
		$a_01_4 = {53 52 56 3a 20 55 50 47 52 41 44 45 20 3c 25 73 3e } //1 SRV: UPGRADE <%s>
		$a_01_5 = {53 52 56 3a 20 49 50 4c 49 53 54 } //1 SRV: IPLIST
		$a_01_6 = {6e 65 77 3d 3c 25 73 3e 2c 20 6f 6c 64 3d 3c 25 73 3e 2c 20 73 65 6c 66 3d 3c 25 73 3e } //1 new=<%s>, old=<%s>, self=<%s>
		$a_01_7 = {77 72 69 74 69 6e 67 20 74 6f 20 48 4b 43 55 2f 61 75 74 6f 72 75 6e 20 6b 65 79 2e 2e 2e } //1 writing to HKCU/autorun key...
		$a_01_8 = {69 73 20 6e 6f 74 20 72 75 6e 6e 69 6e 67 2c 20 75 6e 72 65 73 74 2e } //1 is not running, unrest.
		$a_01_9 = {53 4f 43 4b 53 20 70 6f 72 74 3a 20 25 69 } //1 SOCKS port: %i
		$a_03_10 = {59 b9 40 9c 00 00 99 f7 f9 8d 82 90 01 02 00 00 a3 90 01 02 40 00 a1 90 01 02 40 00 3d 5a 4d 00 00 74 90 01 01 3d 18 06 00 00 74 90 00 } //5
		$a_03_11 = {c7 85 64 ff ff ff fa 00 00 00 e8 90 01 02 ff ff 89 85 7c ff ff ff 85 c0 0f 84 90 01 02 00 00 66 c7 85 6c ff ff ff 02 00 8b 85 7c ff ff ff 89 85 70 ff ff ff 68 e7 14 00 00 90 00 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_03_10  & 1)*5+(#a_03_11  & 1)*5) >=10
 
}