
rule TrojanProxy_Win32_Bunitu_H{
	meta:
		description = "TrojanProxy:Win32/Bunitu.H,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 6f 66 74 5c 56 69 6e 64 6f 77 73 20 4e 55 5c 44 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 56 69 6e 6c 6f 67 6f 6e 5c 4f 6f 74 69 66 79 } //1 soft\Vindows NU\DurrentVersion\Vinlogon\Ootify
		$a_01_1 = {43 6f 6e 74 72 6f 6c 78 65 74 30 30 31 5c 53 65 72 76 69 63 65 73 5c 58 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 } //1 Controlxet001\Services\XharedAccess\Parameters\FirewallPolicy
		$a_01_2 = {ba fd 13 54 50 89 10 81 00 49 40 00 00 ff 00 ff 00 } //1
		$a_01_3 = {c7 40 04 73 32 3f 32 ff 48 04 ff 48 04 81 68 04 0b c6 0b 00 ff 48 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}