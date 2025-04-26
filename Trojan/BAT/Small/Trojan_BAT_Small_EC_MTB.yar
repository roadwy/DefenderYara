
rule Trojan_BAT_Small_EC_MTB{
	meta:
		description = "Trojan:BAT/Small.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {56 6d 74 6b 52 32 56 72 4f 56 68 57 62 6d 73 39 } //1 VmtkR2VrOVhWbms9
		$a_81_1 = {34 39 66 37 37 30 36 35 38 63 36 62 32 37 61 37 } //1 49f770658c6b27a7
		$a_81_2 = {70 61 79 6c 6f 61 64 } //1 payload
		$a_81_3 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_81_4 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //1 SymmetricAlgorithm
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_BAT_Small_EC_MTB_2{
	meta:
		description = "Trojan:BAT/Small.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {2f 43 6f 6d 6d 6f 6e 2f 73 6e 63 6e 78 77 75 74 64 68 77 78 2e 61 73 70 78 } //1 /Common/sncnxwutdhwx.aspx
		$a_81_1 = {38 65 64 62 32 33 31 36 30 64 31 35 37 31 61 30 } //1 8edb23160d1571a0
		$a_81_2 = {2f 43 6f 6d 6d 6f 6e 2f 75 79 69 73 67 68 67 6f 66 77 66 66 2e 61 73 70 78 } //1 /Common/uyisghgofwff.aspx
		$a_81_3 = {48 74 74 70 53 65 72 76 65 72 55 74 69 6c 69 74 79 } //1 HttpServerUtility
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Trojan_BAT_Small_EC_MTB_3{
	meta:
		description = "Trojan:BAT/Small.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d cd } //8
		$a_81_1 = {5b 2b 5d 20 53 75 63 63 65 73 73 66 75 6c 6c 79 20 64 69 73 61 62 6c 65 64 20 41 4d 53 49 21 } //1 [+] Successfully disabled AMSI!
		$a_81_2 = {5b 2b 5d 20 53 75 63 63 65 73 73 66 75 6c 6c 79 20 75 6e 68 6f 6f 6b 65 64 20 45 54 57 21 } //1 [+] Successfully unhooked ETW!
		$a_81_3 = {5b 2b 5d 20 55 52 4c 2f 50 41 54 48 } //1 [+] URL/PATH
	condition:
		((#a_01_0  & 1)*8+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=11
 
}
rule Trojan_BAT_Small_EC_MTB_4{
	meta:
		description = "Trojan:BAT/Small.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {43 6f 6d 6d 6f 6e 2f 6f 64 73 66 64 72 6f 6d 6d 65 63 6b 2e 61 73 70 78 } //1 Common/odsfdrommeck.aspx
		$a_81_1 = {38 65 64 62 32 33 31 36 30 64 31 35 37 31 61 30 } //1 8edb23160d1571a0
		$a_81_2 = {43 6f 6d 6d 6f 6e 2f 65 74 67 61 70 61 62 62 74 67 62 65 2e 61 73 70 78 } //1 Common/etgapabbtgbe.aspx
		$a_81_3 = {43 6f 6d 6d 6f 6e 2f 64 62 62 72 6e 67 6d 79 69 65 65 77 2e 61 73 70 78 } //1 Common/dbbrngmyieew.aspx
		$a_81_4 = {48 74 74 70 53 65 72 76 65 72 55 74 69 6c 69 74 79 } //1 HttpServerUtility
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_BAT_Small_EC_MTB_5{
	meta:
		description = "Trojan:BAT/Small.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 00 48 00 58 00 4c 00 65 00 67 00 61 00 63 00 79 00 2e 00 65 00 78 00 65 00 } //1 PHXLegacy.exe
		$a_01_1 = {64 00 43 00 41 00 72 00 49 00 43 00 49 00 67 00 5a 00 6d 00 6c 00 73 00 5a 00 58 00 4d 00 75 00 49 00 69 00 6b 00 4e 00 43 00 6c 00 64 00 79 00 61 00 58 00 52 00 6c 00 4c 00 55 00 68 00 76 00 63 00 33 00 51 00 67 00 4b 00 43 00 52 00 7a 00 64 00 47 00 39 00 77 00 64 00 47 00 6c 00 74 00 5a 00 53 00 41 00 74 00 49 00 43 00 52 00 7a 00 64 00 47 00 46 00 79 00 64 00 48 00 52 00 70 00 62 00 57 00 55 00 70 00 } //1 dCArICIgZmlsZXMuIikNCldyaXRlLUhvc3QgKCRzdG9wdGltZSAtICRzdGFydHRpbWUp
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {44 6c 6c 49 6d 70 6f 72 74 41 74 74 72 69 62 75 74 65 } //1 DllImportAttribute
		$a_01_4 = {53 79 73 74 65 6d 2e 4d 61 6e 61 67 65 6d 65 6e 74 2e 41 75 74 6f 6d 61 74 69 6f 6e 2e 48 6f 73 74 } //1 System.Management.Automation.Host
		$a_01_5 = {50 53 48 6f 73 74 55 73 65 72 49 6e 74 65 72 66 61 63 65 } //1 PSHostUserInterface
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}