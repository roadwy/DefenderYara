
rule Trojan_Win32_BDPlusSrvc_B_dha{
	meta:
		description = "Trojan:Win32/BDPlusSrvc.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 28 00 00 0a 00 "
		
	strings :
		$a_01_0 = {49 6e 73 74 72 75 63 74 69 6f 6e 3a 3a 74 65 73 74 49 6e 73 74 72 75 63 74 69 6f 6e } //0a 00  Instruction::testInstruction
		$a_01_1 = {49 6e 73 74 72 75 63 74 69 6f 6e 3a 3a 74 64 6b 64 66 6b 76 64 66 } //0a 00  Instruction::tdkdfkvdf
		$a_01_2 = {49 6e 73 74 72 75 63 74 69 6f 6e 3a 3a 6e 6f 43 6d 64 49 6e 73 74 72 75 63 74 69 6f 6e } //0a 00  Instruction::noCmdInstruction
		$a_01_3 = {49 6e 73 74 72 75 63 74 69 6f 6e 3a 3a 64 65 6c 65 74 65 43 6d 64 49 6e 73 74 72 75 63 74 69 6f 6e } //0a 00  Instruction::deleteCmdInstruction
		$a_01_4 = {49 6e 73 74 72 75 63 74 69 6f 6e 3a 3a 64 6f 77 6e 6c 6f 61 64 45 78 63 65 63 75 74 61 62 6c 65 46 69 6c 65 49 6e 73 74 72 75 63 74 69 6f 6e } //0a 00  Instruction::downloadExcecutableFileInstruction
		$a_01_5 = {49 6e 73 74 72 75 63 74 69 6f 6e 3a 3a 75 70 64 61 74 65 52 65 6c 61 79 49 6e 73 74 72 75 63 74 69 6f 6e } //0a 00  Instruction::updateRelayInstruction
		$a_01_6 = {49 6e 73 74 72 75 63 74 69 6f 6e 3a 3a 75 70 64 61 74 65 49 6e 74 65 72 76 61 6c } //0a 00  Instruction::updateInterval
		$a_01_7 = {49 6e 73 74 72 75 63 74 69 6f 6e 3a 3a 64 6f 77 6e 6c 6f 61 64 45 78 63 65 63 75 74 61 62 6c 65 55 72 6c 49 6e 73 74 72 75 63 74 69 6f 6e } //0a 00  Instruction::downloadExcecutableUrlInstruction
		$a_01_8 = {49 6e 73 74 72 75 63 74 69 6f 6e 3a 3a 63 6d 64 45 78 63 65 63 75 74 65 49 6e 73 74 72 75 63 74 69 6f 6e } //0a 00  Instruction::cmdExcecuteInstruction
		$a_01_9 = {49 6e 73 74 72 75 63 74 69 6f 6e 3a 3a 63 72 63 45 72 72 6f 72 49 6e 73 74 72 75 6e 63 74 69 6f 6e } //0a 00  Instruction::crcErrorInstrunction
		$a_01_10 = {49 6e 73 74 72 75 63 74 69 6f 6e 3a 3a 6e 6f 64 65 52 65 67 69 73 74 65 72 49 6e 73 74 72 75 63 74 69 6f 6e } //0a 00  Instruction::nodeRegisterInstruction
		$a_01_11 = {49 6e 73 74 72 75 63 74 69 6f 6e 3a 3a 66 61 69 6c 65 64 49 6e 73 74 72 75 63 74 69 6f 6e } //0a 00  Instruction::failedInstruction
		$a_01_12 = {49 6e 73 74 72 75 63 74 69 6f 6e 3a 3a 61 63 6b 65 64 49 6e 73 74 72 75 63 74 69 6f 6e } //0a 00  Instruction::ackedInstruction
		$a_01_13 = {49 6e 73 74 72 75 63 74 69 6f 6e 3a 3a 6d 65 72 67 65 53 79 73 74 65 6d 49 6e 66 6f } //0a 00  Instruction::mergeSystemInfo
		$a_01_14 = {46 75 6e 63 74 69 6f 6e 73 3a 3a 74 65 73 74 49 6e 73 74 72 75 63 74 69 6f 6e } //0a 00  Functions::testInstruction
		$a_01_15 = {46 75 6e 63 74 69 6f 6e 73 3a 3a 65 74 65 6c 65 64 44 6d 63 49 6e 73 74 72 75 63 74 69 6f 6e } //0a 00  Functions::eteledDmcInstruction
		$a_01_16 = {46 75 6e 63 74 69 6f 6e 73 3a 3a 64 61 6f 6c 6e 77 6f 64 45 6c 62 61 74 75 63 65 78 65 45 6c 69 66 49 6e 73 74 72 75 63 74 69 6f 6e } //0a 00  Functions::daolnwodElbatucexeElifInstruction
		$a_01_17 = {46 75 6e 63 74 69 6f 6e 73 3a 3a 65 74 61 64 70 75 59 61 6c 65 72 49 6e 73 74 72 75 63 74 69 6f 6e } //0a 00  Functions::etadpuYalerInstruction
		$a_01_18 = {46 75 6e 63 74 69 6f 6e 73 3a 3a 65 74 61 64 70 75 4c 61 76 72 65 74 6e 69 49 6e 73 74 72 75 63 74 69 6f 6e } //0a 00  Functions::etadpuLavretniInstruction
		$a_01_19 = {46 75 6e 63 74 69 6f 6e 73 3a 3a 64 61 6f 6c 6e 77 6f 64 45 6c 62 61 74 75 63 65 78 65 4c 72 75 49 6e 73 74 72 75 63 74 69 6f 6e } //0a 00  Functions::daolnwodElbatucexeLruInstruction
		$a_01_20 = {46 75 6e 63 74 69 6f 6e 73 3a 3a 64 6d 63 45 74 75 63 65 63 78 65 49 6e 73 74 72 75 63 74 69 6f 6e } //0a 00  Functions::dmcEtucecxeInstruction
		$a_01_21 = {46 75 6e 63 74 69 6f 6e 73 3a 3a 74 65 67 45 64 6f 6e 4c 6c 75 66 4f 66 6e 69 49 6e 73 74 72 75 63 74 69 6f 6e } //0a 00  Functions::tegEdonLlufOfniInstruction
		$a_01_22 = {46 75 6e 63 74 69 6f 6e 73 3a 3a 63 72 63 45 72 72 6f 72 49 6e 73 74 72 75 6e 63 74 69 6f 6e } //0a 00  Functions::crcErrorInstrunction
		$a_01_23 = {46 75 6e 63 74 69 6f 6e 73 3a 3a 65 64 6f 6e 52 65 74 69 73 69 67 65 72 49 6e 73 74 72 75 63 74 69 6f 6e } //0a 00  Functions::edonRetisigerInstruction
		$a_01_24 = {46 75 6e 63 74 69 6f 6e 73 3a 3a 61 63 6b 65 64 49 6e 73 74 72 75 63 74 69 6f 6e } //0a 00  Functions::ackedInstruction
		$a_01_25 = {46 75 6e 63 74 69 6f 6e 73 3a 3a 6d 65 72 67 65 53 70 6f 6e 73 6f 72 49 6e 66 6f } //02 00  Functions::mergeSponsorInfo
		$a_01_26 = {4e 4f 44 45 5f 52 45 47 } //02 00  NODE_REG
		$a_01_27 = {49 53 5f 43 4d 44 5f 41 56 41 49 4c } //02 00  IS_CMD_AVAIL
		$a_01_28 = {43 4d 44 5f 45 58 45 43 55 54 45 } //02 00  CMD_EXECUTE
		$a_01_29 = {44 4c 5f 45 58 45 43 5f 46 49 4c 45 } //02 00  DL_EXEC_FILE
		$a_01_30 = {44 4c 5f 45 58 45 43 5f 55 52 4c } //02 00  DL_EXEC_URL
		$a_01_31 = {44 45 4c 45 54 45 5f 43 4d 44 } //02 00  DELETE_CMD
		$a_01_32 = {55 50 44 41 54 45 5f 52 45 4c 41 59 53 } //02 00  UPDATE_RELAYS
		$a_01_33 = {55 50 44 41 54 45 5f 49 4e 54 45 52 56 41 4c } //01 00  UPDATE_INTERVAL
		$a_01_34 = {4e 4f 5f 43 4d 44 } //01 00  NO_CMD
		$a_01_35 = {43 52 43 5f 45 52 52 4f 52 } //01 00  CRC_ERROR
		$a_01_36 = {5c 55 6e 69 6e 73 74 61 6c 6c 2e 62 61 74 } //01 00  \Uninstall.bat
		$a_01_37 = {5c 63 6f 6e 66 69 67 2e 74 78 74 } //01 00  \config.txt
		$a_01_38 = {5c 6e 6f 64 65 2e 74 78 74 } //01 00  \node.txt
		$a_01_39 = {5c 72 65 73 75 6c 74 2e 74 78 74 } //00 00  \result.txt
	condition:
		any of ($a_*)
 
}