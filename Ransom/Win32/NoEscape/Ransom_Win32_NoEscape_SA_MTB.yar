
rule Ransom_Win32_NoEscape_SA_MTB{
	meta:
		description = "Ransom:Win32/NoEscape.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 6e 65 74 77 6f 72 6b 20 68 61 73 20 62 65 65 6e 20 68 61 63 6b 65 64 20 61 6e 64 20 69 6e 66 65 63 74 65 64 20 62 79 20 4e 6f 45 73 63 61 70 65 } //1 Your network has been hacked and infected by NoEscape
		$a_01_1 = {48 4f 57 5f 54 4f 5f 52 45 43 4f 56 45 52 5f 46 49 4c 45 53 2e 74 78 74 } //1 HOW_TO_RECOVER_FILES.txt
		$a_01_2 = {57 65 20 61 72 65 20 6e 6f 74 20 61 20 70 6f 6c 69 74 69 63 61 6c 6c 79 20 63 6f 6d 70 61 6e 79 20 61 6e 64 20 77 65 20 61 72 65 20 6e 6f 74 20 69 6e 74 65 72 65 73 74 65 64 20 69 6e 20 79 6f 75 72 20 70 72 69 76 61 74 65 20 61 66 66 61 69 72 73 } //1 We are not a politically company and we are not interested in your private affairs
		$a_01_3 = {70 6f 77 65 72 73 68 65 6c 6c 20 44 69 73 6d 6f 75 6e 74 2d 44 69 73 6b 49 6d 61 67 65 20 2d 49 6d 61 67 65 50 61 74 68 } //1 powershell Dismount-DiskImage -ImagePath
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}