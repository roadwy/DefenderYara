
rule Trojan_Win64_IcedID_AI_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 10 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 69 78 43 6f 6d 70 75 74 65 54 65 78 74 47 65 6f 6d 65 74 72 79 } //01 00  hixComputeTextGeometry
		$a_01_1 = {68 69 78 44 49 74 65 6d 47 65 74 41 6e 63 68 6f 72 } //01 00  hixDItemGetAnchor
		$a_01_2 = {68 69 78 44 49 74 65 6d 53 74 79 6c 65 43 68 61 6e 67 65 64 } //01 00  hixDItemStyleChanged
		$a_01_3 = {68 69 78 44 49 74 65 6d 53 74 79 6c 65 43 6f 6e 66 69 67 75 72 65 47 43 73 } //01 00  hixDItemStyleConfigureGCs
		$a_01_4 = {68 69 78 46 6d 5f 41 64 64 54 6f 4d 61 73 74 65 72 } //01 00  hixFm_AddToMaster
		$a_01_5 = {68 69 78 46 6d 5f 43 6f 6e 66 69 67 75 72 65 } //01 00  hixFm_Configure
		$a_01_6 = {68 69 78 46 6d 5f 44 65 6c 65 74 65 4d 61 73 74 65 72 } //01 00  hixFm_DeleteMaster
		$a_01_7 = {68 69 78 46 6d 5f 46 69 6e 64 43 6c 69 65 6e 74 50 74 72 42 79 4e 61 6d 65 } //01 00  hixFm_FindClientPtrByName
		$a_01_8 = {68 69 78 46 6d 5f 46 6f 72 67 65 74 4f 6e 65 43 6c 69 65 6e 74 } //01 00  hixFm_ForgetOneClient
		$a_01_9 = {68 69 78 46 6d 5f 46 72 65 65 4d 61 73 74 65 72 49 6e 66 6f } //01 00  hixFm_FreeMasterInfo
		$a_01_10 = {68 69 78 46 6d 5f 47 65 74 46 6f 72 6d 49 6e 66 6f } //01 00  hixFm_GetFormInfo
		$a_01_11 = {68 69 78 46 6d 5f 55 6e 6c 69 6e 6b 46 72 6f 6d 4d 61 73 74 65 72 } //01 00  hixFm_UnlinkFromMaster
		$a_01_12 = {68 69 78 47 72 69 64 44 61 74 61 44 65 6c 65 74 65 45 6e 74 72 79 } //01 00  hixGridDataDeleteEntry
		$a_01_13 = {52 74 6c 56 69 72 74 75 61 6c 55 6e 77 69 6e 64 } //01 00  RtlVirtualUnwind
		$a_01_14 = {52 74 6c 43 61 70 74 75 72 65 43 6f 6e 74 65 78 74 } //01 00  RtlCaptureContext
		$a_01_15 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //00 00  GetCurrentProcess
	condition:
		any of ($a_*)
 
}